# Generated by default/object.tt
package Paws::ResourceGroups::GroupConfigurationParameter;
  use Moose;
  has Name => (is => 'ro', isa => 'Str', required => 1);
  has Values => (is => 'ro', isa => 'ArrayRef[Str|Undef]');

1;

### main pod documentation begin ###

=head1 NAME

Paws::ResourceGroups::GroupConfigurationParameter

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::ResourceGroups::GroupConfigurationParameter object:

  $service_obj->Method(Att1 => { Name => $value, ..., Values => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::ResourceGroups::GroupConfigurationParameter object:

  $result = $service_obj->Method(...);
  $result->Att1->Name

=head1 DESCRIPTION

A parameter for a group configuration item. For details about group
service configuration syntax, see Service configurations for resource
groups
(https://docs.aws.amazon.com/ARG/latest/APIReference/about-slg.html).

=head1 ATTRIBUTES


=head2 B<REQUIRED> Name => Str

The name of the group configuration parameter. For the list of
parameters that you can use with each configuration item type, see
Supported resource types and parameters
(https://docs.aws.amazon.com/ARG/latest/APIReference/about-slg.html#about-slg-types).


=head2 Values => ArrayRef[Str|Undef]

The value or values to be used for the specified parameter. For the
list of values you can use with each parameter, see Supported resource
types and parameters
(https://docs.aws.amazon.com/ARG/latest/APIReference/about-slg.html#about-slg-types).



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::ResourceGroups>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

