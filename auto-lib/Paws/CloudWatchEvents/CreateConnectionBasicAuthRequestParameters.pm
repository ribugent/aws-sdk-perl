# Generated by default/object.tt
package Paws::CloudWatchEvents::CreateConnectionBasicAuthRequestParameters;
  use Moose;
  has Password => (is => 'ro', isa => 'Str', required => 1);
  has Username => (is => 'ro', isa => 'Str', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::CloudWatchEvents::CreateConnectionBasicAuthRequestParameters

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::CloudWatchEvents::CreateConnectionBasicAuthRequestParameters object:

  $service_obj->Method(Att1 => { Password => $value, ..., Username => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::CloudWatchEvents::CreateConnectionBasicAuthRequestParameters object:

  $result = $service_obj->Method(...);
  $result->Att1->Password

=head1 DESCRIPTION

Contains the Basic authorization parameters to use for the connection.

=head1 ATTRIBUTES


=head2 B<REQUIRED> Password => Str

The password associated with the user name to use for Basic
authorization.


=head2 B<REQUIRED> Username => Str

The user name to use for Basic authorization.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::CloudWatchEvents>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

