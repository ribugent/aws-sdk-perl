# Generated by default/object.tt
package Paws::LicenseManager::ProductInformation;
  use Moose;
  has ProductInformationFilterList => (is => 'ro', isa => 'ArrayRef[Paws::LicenseManager::ProductInformationFilter]', required => 1);
  has ResourceType => (is => 'ro', isa => 'Str', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::LicenseManager::ProductInformation

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::LicenseManager::ProductInformation object:

  $service_obj->Method(Att1 => { ProductInformationFilterList => $value, ..., ResourceType => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::LicenseManager::ProductInformation object:

  $result = $service_obj->Method(...);
  $result->Att1->ProductInformationFilterList

=head1 DESCRIPTION

Describes product information for a license configuration.

=head1 ATTRIBUTES


=head2 B<REQUIRED> ProductInformationFilterList => ArrayRef[L<Paws::LicenseManager::ProductInformationFilter>]

A Product information filter consists of a
C<ProductInformationFilterComparator> which is a logical operator, a
C<ProductInformationFilterName> which specifies the type of filter
being declared, and a C<ProductInformationFilterValue> that specifies
the value to filter on.

Accepted values for C<ProductInformationFilterName> are listed here
along with descriptions and valid options for
C<ProductInformationFilterComparator>.

The following filters and are supported when the resource type is
C<SSM_MANAGED>:

=over

=item *

C<Application Name> - The name of the application. Logical operator is
C<EQUALS>.

=item *

C<Application Publisher> - The publisher of the application. Logical
operator is C<EQUALS>.

=item *

C<Application Version> - The version of the application. Logical
operator is C<EQUALS>.

=item *

C<Platform Name> - The name of the platform. Logical operator is
C<EQUALS>.

=item *

C<Platform Type> - The platform type. Logical operator is C<EQUALS>.

=item *

C<Tag:key> - The key of a tag attached to an AWS resource you wish to
exclude from automated discovery. Logical operator is C<NOT_EQUALS>.
The key for your tag must be appended to C<Tag:> following the example:
C<Tag:name-of-your-key>. C<ProductInformationFilterValue> is optional
if you are not using values for the key.

=item *

C<AccountId> - The 12-digit ID of an AWS account you wish to exclude
from automated discovery. Logical operator is C<NOT_EQUALS>.

=item *

C<License Included> - The type of license included. Logical operators
are C<EQUALS> and C<NOT_EQUALS>. Possible values are:
C<sql-server-enterprise> | C<sql-server-standard> | C<sql-server-web> |
C<windows-server-datacenter>.

=back

The following filters and logical operators are supported when the
resource type is C<RDS>:

=over

=item *

C<Engine Edition> - The edition of the database engine. Logical
operator is C<EQUALS>. Possible values are: C<oracle-ee> | C<oracle-se>
| C<oracle-se1> | C<oracle-se2>.

=item *

C<License Pack> - The license pack. Logical operator is C<EQUALS>.
Possible values are: C<data guard> | C<diagnostic pack sqlt> | C<tuning
pack sqlt> | C<ols> | C<olap>.

=back



=head2 B<REQUIRED> ResourceType => Str

Resource type. The possible values are C<SSM_MANAGED> | C<RDS>.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::LicenseManager>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

